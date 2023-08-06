use serde::Deserialize;

structstruck::strike! {
    #[strikethrough[derive(Deserialize, Debug)]]
    #[serde(rename_all = "snake_case")]
    #[serde(tag = "result")]
    pub enum PreauthResponse {
        Auth {
            devices: Vec<pub struct Device {
                pub capabilities: Option<Vec<#[serde(rename_all = "snake_case")] pub enum DeviceCapability {
                    Auto,
                    Push,
                    Sms,
                    Phone,
                    MobileOtp,
                }>>,
                pub device: String,
                pub display_name: Option<String>,
                pub name: String,
                pub number: String,
                pub sms_nextcode: Option<String>,
                pub r#type: #[serde(rename_all = "snake_case")] pub enum DeviceType {
                    Phone,
                    Token,
                },

            }>,
        },
        Enroll {
            enroll_portal_url: String,
        },
        Allow,
        Deny,
    }
}
