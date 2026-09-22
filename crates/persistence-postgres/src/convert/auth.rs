use nazo_auth::BackchannelLogoutDelivery;

use crate::rows::auth::BackchannelLogoutDeliveryRow;

impl From<BackchannelLogoutDeliveryRow> for BackchannelLogoutDelivery {
    fn from(row: BackchannelLogoutDeliveryRow) -> Self {
        Self {
            id: row.id,
            logout_uri: row.logout_uri,
            logout_token: row.logout_token,
            attempts: row.attempts,
            expires_at: row.expires_at,
        }
    }
}
