use std::collections::HashMap;
use std::sync::Arc;

use tonic::{Request, Response, Status};

use super::server::custom::service::ratelimit::v1::rate_limit_service_server::RateLimitService;
use super::server::envoy::service::ratelimit::v3::rate_limit_response::Code;
use super::server::envoy::service::ratelimit::v3::{RateLimitRequest, RateLimitResponse};
use crate::prometheus_metrics::PrometheusMetrics;
use crate::Limiter;
use limitador::limit::Context;
use crate::openai_debug::log_openai_debug;

pub struct KuadrantService {
    limiter: Arc<Limiter>,
    metrics: Arc<PrometheusMetrics>,
}

impl KuadrantService {
    pub fn new(limiter: Arc<Limiter>, metrics: Arc<PrometheusMetrics>) -> Self {
        Self { limiter, metrics }
    }
}

#[tonic::async_trait]
impl RateLimitService for KuadrantService {
    #[tracing::instrument(skip_all)]
    async fn check_rate_limit(
        &self,
        request: Request<RateLimitRequest>,
    ) -> Result<Response<RateLimitResponse>, Status> {
        debug!("CheckRateLimit request received: {:?}", request);

        let mut values: Vec<HashMap<String, String>> = Vec::default();
        let (_metadata, _ext, req) = request.into_parts();
        let namespace = req.domain;

        if namespace.is_empty() {
            return Ok(Response::new(RateLimitResponse {
                overall_code: Code::Unknown.into(),
                statuses: vec![],
                request_headers_to_add: vec![],
                response_headers_to_add: vec![],
                raw_body: vec![],
                dynamic_metadata: None,
                quota: None,
            }));
        }

        let namespace = namespace.into();

        // Extract user/group from descriptors for metrics labeling
        let mut user_id: Option<String> = None;
        let mut group: Option<String> = None;

        let mut flat_map: HashMap<String, String> = HashMap::default();
        for descriptor in &req.descriptors {
            let mut map = HashMap::default();
            for entry in &descriptor.entries {
                if entry.key == "auth.identity.userid" {
                    user_id = Some(entry.value.clone());
                }
                if entry.key == "auth.identity.metadata.annotations.kuadrant.io/groups" {
                    group = Some(entry.value.clone());
                }
                map.insert(entry.key.clone(), entry.value.clone());
                flat_map.insert(entry.key.clone(), entry.value.clone());
            }
            values.push(map);
        }

        let mut ctx = Context::default();
        ctx.list_binding("descriptors".to_string(), values);

        // Best-effort OpenAI request debug logging (opt-in via env)
        log_openai_debug(&flat_map, None);

        let rate_limited_resp = match &*self.limiter {
            Limiter::Blocking(limiter) => limiter.is_rate_limited(&namespace, &ctx, 1),
            Limiter::Async(limiter) => limiter.is_rate_limited(&namespace, &ctx, 1).await,
        };

        if let Err(e) = rate_limited_resp {
            // In this case we could return "Code::Unknown" but that's not
            // very helpful. When envoy receives "Unknown" it simply lets
            // the request pass and this cannot be configured using the
            // "failure_mode_deny" attribute, so it's equivalent to
            // returning "Code::Ok". That's why we return an "unavailable"
            // error here. What envoy does after receiving that kind of
            // error can be configured with "failure_mode_deny". The only
            // errors that can happen here have to do with connecting to the
            // limits storage, which should be temporary.
            error!("Error: {:?}", e);
            return Err(Status::unavailable("Service unavailable"));
        }

        let limited = rate_limited_resp.unwrap();

        // Increment metrics: limited calls on overlimit, authorized_calls on OK (hits added in report)
        if limited {
            self.metrics.incr_limited_calls_with_user_and_group(
                &namespace,
                None,
                user_id.as_deref(),
                group.as_deref(),
            );
        } else {
            // increment authorized_calls without adding hits yet
            self.metrics.incr_authorized_calls_with_user_and_group(
                &namespace,
                user_id.as_deref(),
                group.as_deref(),
                0,
            );
        }

        let resp_code = if limited { Code::OverLimit } else { Code::Ok };

        let reply = RateLimitResponse {
            overall_code: resp_code.into(),
            statuses: vec![],
            request_headers_to_add: vec![],
            response_headers_to_add: vec![],
            raw_body: vec![],
            dynamic_metadata: None,
            quota: None,
        };

        Ok(Response::new(reply))
    }

    #[tracing::instrument(skip_all)]
    async fn report(
        &self,
        request: Request<RateLimitRequest>,
    ) -> Result<Response<RateLimitResponse>, Status> {
        debug!("Report request received: {:?}", request);

        let mut values: Vec<HashMap<String, String>> = Vec::default();
        let (_metadata, _ext, req) = request.into_parts();
        let namespace = req.domain;

        if namespace.is_empty() {
            return Ok(Response::new(RateLimitResponse {
                overall_code: Code::Unknown.into(),
                statuses: vec![],
                request_headers_to_add: vec![],
                response_headers_to_add: vec![],
                raw_body: vec![],
                dynamic_metadata: None,
                quota: None,
            }));
        }

        let namespace = namespace.into();

        // Extract user/group from descriptors for metrics labeling
        let mut user_id: Option<String> = None;
        let mut group: Option<String> = None;

        let mut flat_map: HashMap<String, String> = HashMap::default();
        for descriptor in &req.descriptors {
            let mut map = HashMap::default();
            for entry in &descriptor.entries {
                if entry.key == "auth.identity.userid" {
                    user_id = Some(entry.value.clone());
                }
                if entry.key == "auth.identity.metadata.annotations.kuadrant.io/groups" {
                    group = Some(entry.value.clone());
                }
                map.insert(entry.key.clone(), entry.value.clone());
                flat_map.insert(entry.key.clone(), entry.value.clone());
            }
            values.push(map);
        }

        let mut ctx = Context::default();
        ctx.list_binding("descriptors".to_string(), values);

        // Best-effort OpenAI request debug logging (opt-in via env)
        log_openai_debug(&flat_map, Some(req.hits_addend as u64));

        let rate_limited_resp = match &*self.limiter {
            Limiter::Blocking(limiter) => {
                limiter.update_counters(&namespace, &ctx, req.hits_addend as u64)
            }
            Limiter::Async(limiter) => {
                limiter
                    .update_counters(&namespace, &ctx, req.hits_addend as u64)
                    .await
            }
        };

        if let Err(e) = rate_limited_resp {
            // In this case we could return "Code::Unknown" but that's not
            // very helpful. When envoy receives "Unknown" it simply lets
            // the request pass and this cannot be configured using the
            // "failure_mode_deny" attribute, so it's equivalent to
            // returning "Code::Ok". That's why we return an "unavailable"
            // error here. What envoy does after receiving that kind of
            // error can be configured with "failure_mode_deny". The only
            // errors that can happen here have to do with connecting to the
            // limits storage, which should be temporary.
            error!("Error: {:?}", e);
            return Err(Status::unavailable("Service unavailable"));
        }

        // Record token increments on report
        self.metrics.incr_authorized_calls_with_user_and_group(
            &namespace,
            user_id.as_deref(),
            group.as_deref(),
            req.hits_addend as u64,
        );

        let reply = RateLimitResponse {
            overall_code: Code::Ok as i32,
            statuses: vec![],
            request_headers_to_add: vec![],
            response_headers_to_add: vec![],
            raw_body: vec![],
            dynamic_metadata: None,
            quota: None,
        };

        Ok(Response::new(reply))
    }
}

#[cfg(test)]
mod tests {
    mod check_rate_limit {
        use tonic::IntoRequest;

        use limitador::limit::Limit;
        use limitador::RateLimiter;

        use crate::envoy_rls::server::envoy::extensions::common::ratelimit::v3::rate_limit_descriptor::Entry;
        use crate::envoy_rls::server::envoy::extensions::common::ratelimit::v3::RateLimitDescriptor;
        use crate::envoy_rls::server::envoy::service::ratelimit::v3::RateLimitRequest;

        use super::super::*;

        // All these tests use the in-memory storage implementation to simplify. We
        // know that some storage implementations like the Redis one trade
        // rate-limiting accuracy for performance. That would be a bit more
        // complicated to test.
        // Also, the logic behind these endpoints is well tested in the library,
        // that's why running some simple tests here should be enough.

        #[tokio::test]
        async fn test_returns_ok_correctly() {
            let namespace = "test_namespace";
            let limit = Limit::new(
                namespace,
                1,
                60,
                vec!["descriptors[0]['req.method'] == 'GET'"
                    .try_into()
                    .expect("failed parsing!")],
                vec!["descriptors[0]['app.id']"
                    .try_into()
                    .expect("failed parsing!")],
            );

            let limiter = RateLimiter::new(10_000);
            limiter.add_limit(limit);

            let rate_limiter = KuadrantService::new(
                Arc::new(Limiter::Blocking(limiter)),
                Arc::new(crate::prometheus_metrics::PrometheusMetrics::new()),
            );

            let req = RateLimitRequest {
                domain: namespace.to_string(),
                descriptors: vec![RateLimitDescriptor {
                    entries: vec![
                        Entry {
                            key: "req.method".to_string(),
                            value: "GET".to_string(),
                        },
                        Entry {
                            key: "app.id".to_string(),
                            value: "1".to_string(),
                        },
                    ],
                    limit: None,
                }],
                hits_addend: 1, // irrelevant for this test
            };

            // There's a limit of 1, so the first request should return "OK"

            let response = rate_limiter
                .check_rate_limit(req.clone().into_request())
                .await
                .unwrap()
                .into_inner();
            assert_eq!(response.overall_code, i32::from(Code::Ok));

            let response = rate_limiter
                .check_rate_limit(req.clone().into_request())
                .await
                .unwrap()
                .into_inner();
            assert_eq!(response.overall_code, i32::from(Code::Ok));
        }

        #[tokio::test]
        async fn test_returns_overlimit_correctly() {
            let namespace = "test_namespace";
            let limit = Limit::new(
                namespace,
                0,
                60,
                vec!["descriptors[0]['req.method'] == 'GET'"
                    .try_into()
                    .expect("failed parsing!")],
                vec!["descriptors[0]['app.id']"
                    .try_into()
                    .expect("failed parsing!")],
            );

            let limiter = RateLimiter::new(10_000);
            limiter.add_limit(limit);

            let rate_limiter = KuadrantService::new(
                Arc::new(Limiter::Blocking(limiter)),
                Arc::new(crate::prometheus_metrics::PrometheusMetrics::new()),
            );

            let req = RateLimitRequest {
                domain: namespace.to_string(),
                descriptors: vec![RateLimitDescriptor {
                    entries: vec![
                        Entry {
                            key: "req.method".to_string(),
                            value: "GET".to_string(),
                        },
                        Entry {
                            key: "app.id".to_string(),
                            value: "1".to_string(),
                        },
                    ],
                    limit: None,
                }],
                hits_addend: 1, // irrelevant for this test
            };

            // There's a limit of 1, so the first request should return "OK" and the
            // second "OverLimit".

            let response = rate_limiter
                .check_rate_limit(req.into_request())
                .await
                .unwrap()
                .into_inner();
            assert_eq!(response.overall_code, i32::from(Code::OverLimit));
        }

        #[tokio::test]
        async fn test_returns_ok_when_no_limits_apply() {
            // No limits saved
            let limiter = RateLimiter::new(10_000);
            let rate_limiter = KuadrantService::new(
                Arc::new(Limiter::Blocking(limiter)),
                Arc::new(crate::prometheus_metrics::PrometheusMetrics::new()),
            );

            let req = RateLimitRequest {
                domain: "test_namespace".to_string(),
                descriptors: vec![RateLimitDescriptor {
                    entries: vec![Entry {
                        key: "req.method".to_string(),
                        value: "GET".to_string(),
                    }],
                    limit: None,
                }],
                hits_addend: 1,
            }
            .into_request();

            let response = rate_limiter
                .check_rate_limit(req)
                .await
                .unwrap()
                .into_inner();

            assert_eq!(response.overall_code, i32::from(Code::Ok));
        }

        #[tokio::test]
        async fn test_returns_unknown_when_domain_is_empty() {
            let limiter = RateLimiter::new(10_000);
            let rate_limiter = KuadrantService::new(
                Arc::new(Limiter::Blocking(limiter)),
                Arc::new(crate::prometheus_metrics::PrometheusMetrics::new()),
            );

            let req = RateLimitRequest {
                domain: "".to_string(),
                descriptors: vec![RateLimitDescriptor {
                    entries: vec![Entry {
                        key: "req.method".to_string(),
                        value: "GET".to_string(),
                    }],
                    limit: None,
                }],
                hits_addend: 1,
            }
            .into_request();

            let response = rate_limiter
                .check_rate_limit(req)
                .await
                .unwrap()
                .into_inner();
            assert_eq!(response.overall_code, i32::from(Code::Unknown));
        }

        #[tokio::test]
        async fn test_takes_into_account_all_the_descriptors() {
            let limiter = RateLimiter::new(10_000);

            let namespace = "test_namespace";

            vec![
                Limit::new(
                    namespace,
                    10,
                    60,
                    vec!["descriptors[0].x == '1'"
                        .try_into()
                        .expect("failed parsing!")],
                    vec!["descriptors[0].z".try_into().expect("failed parsing!")],
                ),
                Limit::new(
                    namespace,
                    0,
                    60,
                    vec![
                        "descriptors[0].x == '1'"
                            .try_into()
                            .expect("failed parsing!"),
                        "descriptors[1].y == '2'"
                            .try_into()
                            .expect("failed parsing!"),
                    ],
                    vec!["descriptors[0].z".try_into().expect("failed parsing!")],
                ),
            ]
            .into_iter()
            .for_each(|limit| {
                limiter.add_limit(limit);
            });

            let rate_limiter = KuadrantService::new(
                Arc::new(Limiter::Blocking(limiter)),
                Arc::new(crate::prometheus_metrics::PrometheusMetrics::new()),
            );

            let req = RateLimitRequest {
                domain: namespace.to_string(),
                descriptors: vec![
                    RateLimitDescriptor {
                        entries: vec![
                            Entry {
                                key: "x".to_string(),
                                value: "1".to_string(),
                            },
                            Entry {
                                key: "z".to_string(),
                                value: "1".to_string(),
                            },
                        ],
                        limit: None,
                    },
                    // If this is taken into account, the result will be "overlimit"
                    // because of the second limit that has a max of 0.
                    RateLimitDescriptor {
                        entries: vec![Entry {
                            key: "y".to_string(),
                            value: "2".to_string(),
                        }],
                        limit: None,
                    },
                ],
                hits_addend: 1,
            };

            let response = rate_limiter
                .check_rate_limit(req.into_request())
                .await
                .unwrap()
                .into_inner();

            assert_eq!(response.overall_code, i32::from(Code::OverLimit));
        }
    }

    mod report {
        use tonic::IntoRequest;

        use limitador::limit::Limit;
        use limitador::RateLimiter;

        use crate::envoy_rls::server::envoy::extensions::common::ratelimit::v3::rate_limit_descriptor::Entry;
        use crate::envoy_rls::server::envoy::extensions::common::ratelimit::v3::RateLimitDescriptor;
        use crate::envoy_rls::server::envoy::service::ratelimit::v3::RateLimitRequest;

        use super::super::*;

        #[tokio::test]
        async fn test_returns_ok_correctly() {
            let namespace = "test_namespace";
            let limit = Limit::new(
                namespace,
                10,
                60,
                vec!["descriptors[0]['req.method'] == 'GET'"
                    .try_into()
                    .expect("failed parsing!")],
                vec!["descriptors[0]['app.id']"
                    .try_into()
                    .expect("failed parsing!")],
            );

            let limiter = RateLimiter::new(10_000);
            limiter.add_limit(limit);

            let rate_limiter = KuadrantService::new(
                Arc::new(Limiter::Blocking(limiter)),
                Arc::new(crate::prometheus_metrics::PrometheusMetrics::new()),
            );

            let req = RateLimitRequest {
                domain: namespace.to_string(),
                descriptors: vec![RateLimitDescriptor {
                    entries: vec![
                        Entry {
                            key: "req.method".to_string(),
                            value: "GET".to_string(),
                        },
                        Entry {
                            key: "app.id".to_string(),
                            value: "1".to_string(),
                        },
                    ],
                    limit: None,
                }],
                hits_addend: 4,
            };

            let response = rate_limiter
                .report(req.clone().into_request())
                .await
                .unwrap()
                .into_inner();
            assert_eq!(response.overall_code, i32::from(Code::Ok));
        }

        #[tokio::test]
        async fn test_going_overlimit_is_ok() {
            let namespace = "test_namespace";
            let limit = Limit::new(
                namespace,
                5,
                60,
                vec!["descriptors[0]['req.method'] == 'GET'"
                    .try_into()
                    .expect("failed parsing!")],
                vec!["descriptors[0]['app.id']"
                    .try_into()
                    .expect("failed parsing!")],
            );

            let limiter = RateLimiter::new(10_000);
            limiter.add_limit(limit);

            let rate_limiter = KuadrantService::new(
                Arc::new(Limiter::Blocking(limiter)),
                Arc::new(crate::prometheus_metrics::PrometheusMetrics::new()),
            );

            let req = RateLimitRequest {
                domain: namespace.to_string(),
                descriptors: vec![RateLimitDescriptor {
                    entries: vec![
                        Entry {
                            key: "req.method".to_string(),
                            value: "GET".to_string(),
                        },
                        Entry {
                            key: "app.id".to_string(),
                            value: "1".to_string(),
                        },
                    ],
                    limit: None,
                }],
                hits_addend: 20,
            };

            let response = rate_limiter
                .report(req.into_request())
                .await
                .unwrap()
                .into_inner();
            assert_eq!(response.overall_code, i32::from(Code::Ok));
        }

        #[tokio::test]
        async fn test_returns_ok_when_no_limits_apply() {
            // No limits saved
            let limiter = RateLimiter::new(10_000);
            let rate_limiter = KuadrantService::new(
                Arc::new(Limiter::Blocking(limiter)),
                Arc::new(crate::prometheus_metrics::PrometheusMetrics::new()),
            );

            let req = RateLimitRequest {
                domain: "test_namespace".to_string(),
                descriptors: vec![RateLimitDescriptor {
                    entries: vec![Entry {
                        key: "req.method".to_string(),
                        value: "GET".to_string(),
                    }],
                    limit: None,
                }],
                hits_addend: 1,
            }
            .into_request();

            let response = rate_limiter.report(req).await.unwrap().into_inner();

            assert_eq!(response.overall_code, i32::from(Code::Ok));
        }

        #[tokio::test]
        async fn test_returns_unknown_when_domain_is_empty() {
            let limiter = RateLimiter::new(10_000);
            let rate_limiter = KuadrantService::new(Arc::new(Limiter::Blocking(limiter)));

            let req = RateLimitRequest {
                domain: "".to_string(),
                descriptors: vec![RateLimitDescriptor {
                    entries: vec![Entry {
                        key: "req.method".to_string(),
                        value: "GET".to_string(),
                    }],
                    limit: None,
                }],
                hits_addend: 1,
            }
            .into_request();

            let response = rate_limiter.report(req).await.unwrap().into_inner();
            assert_eq!(response.overall_code, i32::from(Code::Unknown));
        }
    }
}
