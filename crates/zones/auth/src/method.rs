use crate::Permission;
use serde_json::Value;

macro_rules! methods {
    ($($variant:ident => $name:literal, $permission:ident),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum RpcMethod { $($variant,)+ }
        impl RpcMethod {
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];
            pub fn from_name(name: &str) -> Option<Self> {
                match name { $($name => Some(Self::$variant),)+ _ => None }
            }
            pub const fn name(self) -> &'static str {
                match self { $(Self::$variant => $name,)+ }
            }
            pub fn metric_label(name: &str) -> &'static str {
                Self::from_name(name).map(Self::name).unwrap_or("unknown")
            }
            pub const fn permission(self) -> Permission {
                match self { $(Self::$variant => Permission::$permission,)+ }
            }
        }
    };
}

methods! {
    EthBlockNumber => "eth_blockNumber", Metadata,
    EthChainId => "eth_chainId", Metadata,
    EthGasPrice => "eth_gasPrice", Metadata,
    EthGetBalance => "eth_getBalance", RpcRead,
    EthGetTransactionCount => "eth_getTransactionCount", RpcRead,
    EthCall => "eth_call", RpcRead,
    EthEstimateGas => "eth_estimateGas", RpcRead,
    EthFeeHistory => "eth_feeHistory", Metadata,
    EthMaxPriorityFeePerGas => "eth_maxPriorityFeePerGas", Metadata,
    EthGetBlockByNumber => "eth_getBlockByNumber", Metadata,
    EthGetBlockByHash => "eth_getBlockByHash", Metadata,
    EthSyncing => "eth_syncing", Metadata,
    EthCoinbase => "eth_coinbase", Metadata,
    NetVersion => "net_version", Metadata,
    NetListening => "net_listening", Metadata,
    Web3ClientVersion => "web3_clientVersion", Metadata,
    Web3Sha3 => "web3_sha3", Metadata,
    ZoneGetAuthorizationTokenInfo => "zone_getAuthorizationTokenInfo", Metadata,
    ZoneGetZoneInfo => "zone_getZoneInfo", Metadata,
    ZoneGetEncryptionKey => "zone_getEncryptionKey", Metadata,
    EthGetTransactionByHash => "eth_getTransactionByHash", RpcRead,
    EthGetTransactionReceipt => "eth_getTransactionReceipt", RpcRead,
    EthGetLogs => "eth_getLogs", RpcRead,
    EthGetFilterLogs => "eth_getFilterLogs", RpcRead,
    EthGetFilterChanges => "eth_getFilterChanges", RpcRead,
    EthNewFilter => "eth_newFilter", RpcRead,
    EthNewBlockFilter => "eth_newBlockFilter", RpcRead,
    EthUninstallFilter => "eth_uninstallFilter", RpcRead,
    EthFillTransaction => "eth_fillTransaction", RpcRead,
    EthSendRawTransaction => "eth_sendRawTransaction", RpcWrite,
    EthSendRawTransactionSync => "eth_sendRawTransactionSync", RpcWrite,
    EthSubscribe => "eth_subscribe", Metadata,
    EthUnsubscribe => "eth_unsubscribe", Metadata,
}

/// Classifies every externally supported call; subscription subtype is load-bearing.
/// Unsubscribe requires a separately checked owned handle even after permission removal.
pub fn rpc_permission(method: &str, params: &Value) -> Option<Permission> {
    let method = RpcMethod::from_name(method)?;
    if method == RpcMethod::EthSubscribe {
        let params = params.as_array()?;
        return match params.first()?.as_str()? {
            "newHeads" if params.len() == 1 => Some(Permission::Metadata),
            "logs" if (1..=2).contains(&params.len()) => Some(Permission::RpcRead),
            _ => None,
        };
    }
    Some(method.permission())
}
