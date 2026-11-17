// Native regression module: reexports the actual neutral implementation.

use super::*;

pub(crate) async fn parse_backchannel_authentication_form(
    req: &HttpRequest,
    payload: &mut Payload,
) -> Result<BackchannelAuthenticationForm, HttpResponse> {
    let request = crate::test_support::transport::request_head(req);
    (nazoauth::test_support::endpoints::token::ciba::request::parse_backchannel_authentication_form(&request, crate::test_support::transport::ciba_body(payload)).await).map_err(nazo_http_actix::forward_response)
}
