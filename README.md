# wechatPay
微信支付

配置自己的支付参数
var AppId = ""          //公众号appid
var AppSecret = ""      //公众号秘钥
var MerId = ""          //商户号
var PayKey = ""         //商户秘钥
var NotifyUrl = ""      //公众号支付回调
var SpbillCreateIp = "" //发起请求的机器ip
var NativeUrl = ""      //扫码支付回调


JsApiPay 获取公众号支付信息（生成预支付订单）

JsApiPayCallBack 公众号支付回调

NativePay 回去扫码支付二维码

NativeCallback 扫码支付回调
