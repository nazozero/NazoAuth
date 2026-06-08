mod admin;
mod auth;
mod authorization;
mod fapi_resource;
mod profile;
mod scim;
mod token;
mod well_known;

pub(crate) use admin::*;
pub(crate) use auth::*;
pub(crate) use authorization::*;
pub(crate) use fapi_resource::*;
pub(crate) use profile::*;
pub(crate) use scim::*;
pub(crate) use token::*;
pub(crate) use well_known::*;

pub(crate) mod prelude {
    pub(crate) use std::collections::HashMap;

    pub(crate) use actix_multipart::Multipart;
    pub(crate) use actix_web::{
        HttpRequest, HttpResponse,
        http::{
            StatusCode,
            header::{self, HeaderValue},
        },
        web::Bytes,
        web::{Data, Form, Json, Query},
    };
    pub(crate) use chrono::{DateTime, Duration, Utc};
    pub(crate) use diesel::{
        OptionalExtension,
        dsl::{count_star, now as diesel_now},
        prelude::*,
    };
    pub(crate) use diesel_async::RunQueryDsl;
    pub(crate) use futures_util::StreamExt;
    pub(crate) use serde::Deserialize;
    pub(crate) use serde_json::{Value, json};
    pub(crate) use uuid::Uuid;

    pub(crate) use crate::db::get_conn;
    pub(crate) use crate::domain::{
        AccessRequestStatus, AppState, AuthorizationCodeState, ClientRow, CodePayload,
        ConsentPayload, ConsumedAuthorizationCode, ExternalIdentityLinkRow, GrantRow,
        MyApplicationRow, OidcClaimRequest, PasskeyCredentialRow, PendingAccessRequestRow,
        PushedAuthorizationRequest, RefreshTokenPolicy, TokenIssue, TokenRow, UserAccessRequestRow,
        UserRow, authorization_details_empty, canonical_authorization_details,
        high_risk_authorization_details, normalize_authorization_details,
        parse_authorization_details,
    };
    pub(crate) use crate::schema::{
        access_token_revocations, client_access_requests, external_identity_links, oauth_clients,
        oauth_tokens, scim_audit_events, scim_tokens, user_client_grants, user_passkey_credentials,
        user_totp_credentials, users,
    };
    pub(crate) use crate::settings::Settings;
    pub(crate) use crate::support::*;
}
