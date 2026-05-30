//! 跨 HTTP handler 复用的领域支撑模块。
// 子模块按职责拆分；外部仍通过 crate::support::* 使用稳定入口。
mod access_requests;
mod avatars;
mod cookies;
mod dpop;
mod email;
mod email_templates;
mod keyset;
mod oauth;
mod repositories;
mod responses;
mod security;
mod sessions;
mod valkey;
mod views;

pub(crate) use access_requests::*;
pub(crate) use avatars::*;
pub(crate) use cookies::*;
pub(crate) use dpop::*;
pub(crate) use email::*;
pub(crate) use keyset::*;
pub(crate) use oauth::*;
pub(crate) use repositories::*;
pub(crate) use responses::*;
pub(crate) use security::*;
pub(crate) use sessions::*;
pub(crate) use valkey::*;
pub(crate) use views::*;

pub(crate) mod prelude {
    pub(crate) use std::{collections::HashMap, path::PathBuf};

    pub(crate) use actix_web::cookie::{Cookie, SameSite, time::Duration as CookieDuration};
    pub(crate) use actix_web::http::{
        StatusCode,
        header::{self, HeaderMap, HeaderValue},
    };
    pub(crate) use actix_web::{HttpRequest, HttpResponse};
    pub(crate) use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
    pub(crate) use base64::{
        Engine,
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    };
    pub(crate) use chrono::Utc;
    pub(crate) use diesel::{dsl::count, prelude::*};
    pub(crate) use diesel_async::RunQueryDsl;
    pub(crate) use ed25519_dalek::SigningKey;
    pub(crate) use fred::prelude::{
        Client as ValkeyClient, Error as ValkeyError, Expiration, KeysInterface, SetOptions,
    };
    pub(crate) use password_hash::{SaltString, rand_core::OsRng};
    pub(crate) use serde::Serialize;
    pub(crate) use serde_json::{Value, json};
    pub(crate) use sha2::{Digest, Sha256};
    pub(crate) use uuid::Uuid;

    pub(crate) use crate::db::{DbPool, get_conn};
    pub(crate) use crate::domain::{
        AccessRequestRow, AccessRequestStatus, AppState, Claims, ClientRow, ConfirmationClaims,
        Keyset, UserRow,
    };
    pub(crate) use crate::schema::{
        client_access_requests, oauth_clients, user_client_grants, users,
    };
    pub(crate) use crate::settings::Settings;

    pub(crate) use super::{
        clear_cookie, constant_time_eq, cookie_value, find_client, find_user_by_id,
        json_array_to_strings, read_avatar_version, sorted_scope_string, valkey_get,
        with_cookie_headers,
    };
}
