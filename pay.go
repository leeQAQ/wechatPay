package controllers

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"crypto/tls"

	"crypto/md5"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"io"
	"sort"

	"github.com/astaxie/beego"
)

//配置参数
var AppId = ""          //公众号appid
var AppSecret = ""      //公众号秘钥
var MerId = ""          //商户号
var PayKey = ""         //商户秘钥
var NotifyUrl = ""      //公众号支付回调
var SpbillCreateIp = "" //发起请求的机器ip
var NativeUrl = ""      //扫码支付回调

//支付
type PayController struct {
	beego.Controller
}
type NativeRequest struct {
	Money int `json:"money" description:"*金额"`
}
type JsApiPayRequest struct {
	OpenId    string  `json:"openId" description:"*用户openId"`
	HelpMoney float64 `json:"helpMoney" description:"金额"`
}
type SignModel struct {
	Appid     string `json:"appid" description:"公众号appid"`
	NonceStr  string `json:"nonceStr" description:"随机字符串"`
	Package   string `json:"package" description:"预支付订单编号"`
	SignType  string `json:"signType" description:"签名类型"`
	Signature string `json:"signature" description:"签名"`
	TimeStamp string `json:"timeStamp" description:"时间戳"`
}

// @Summary 支付签名
func (this *PayController) JsApiPay() {
	var openId = "" //支付用户的openId
	nowTime := time.Now().Unix()
	nowTimeStr := strconv.FormatInt(nowTime, 10)
	var Nonce_str = nowTimeStr
	//请求UnifiedOrder的代码
	var yourReq UnifyOrderReq
	yourReq.Appid = AppId //微信开放平台我们创建出来的app的app id
	yourReq.Body = "支付"
	yourReq.Mch_id = MerId
	yourReq.Nonce_str = Nonce_str
	yourReq.Notify_url = NotifyUrl
	yourReq.Trade_type = "JSAPI"
	yourReq.Spbill_create_ip = SpbillCreateIp
	yourReq.Total_fee = 1 //单位是分，这里是1分钱
	yourReq.Out_trade_no = "12345678"
	yourReq.OpenId = openId
	var m map[string]interface{}
	m = make(map[string]interface{}, 0)
	m["appid"] = yourReq.Appid
	m["body"] = yourReq.Body
	m["mch_id"] = yourReq.Mch_id
	m["notify_url"] = yourReq.Notify_url
	m["trade_type"] = yourReq.Trade_type
	m["spbill_create_ip"] = yourReq.Spbill_create_ip
	m["total_fee"] = yourReq.Total_fee
	m["out_trade_no"] = yourReq.Out_trade_no
	m["nonce_str"] = yourReq.Nonce_str
	m["openid"] = yourReq.OpenId
	yourReq.Sign = WxpayCalcSign(m, PayKey) //这个是计算wxpay签名的函数上面已贴出

	bytes_req, err := xml.Marshal(yourReq)
	if err != nil {
		fmt.Println("以xml形式编码发送错误, 原因:", err)
	}

	str_req := string(bytes_req)
	//wxpay的unifiedorder接口需要http body中xmldoc的根节点是<xml></xml>这种，所以这里需要replace一下
	str_req = strings.Replace(str_req, "UnifyOrderReq", "xml", -1)
	bytes_req = []byte(str_req)

	//发送unified order请求.
	req, err := http.NewRequest("POST", "https://api.mch.weixin.qq.com/pay/unifiedorder", bytes.NewReader(bytes_req))
	if err != nil {
		fmt.Println("New Http Request发生错误，原因:", err)

	}
	req.Header.Set("Accept", "application/xml")
	//这里的http header的设置是必须设置的.
	req.Header.Set("Content-Type", "application/xml;charset=utf-8")

	c := http.Client{}
	resp, _err := c.Do(req)
	if _err != nil {
		fmt.Println("请求微信支付统一下单接口发送错误, 原因:", _err)

	}

	//到这里统一下单接口就已经执行完成了
	xmlResp := UnifyOrderResp{}
	buf, err := ioutil.ReadAll(resp.Body)
	_err = xml.Unmarshal(buf, &xmlResp)
	//处理return code.
	if xmlResp.Return_code == "FAIL" {
		fmt.Println("微信支付统一下单不成功，原因:", xmlResp.Return_msg)

	}

	//这里已经得到微信支付的prepay id，需要返给客户端，由客户端继续完成支付流程
	fmt.Println("微信支付统一下单成功，预支付单号:", xmlResp.Prepay_id)
	var d map[string]interface{}
	timeStamp := strconv.FormatInt(nowTime+1, 10)
	d = make(map[string]interface{}, 0)
	d["appId"] = AppId
	d["timeStamp"] = timeStamp
	d["nonceStr"] = nowTimeStr
	d["package"] = "prepay_id=" + xmlResp.Prepay_id
	d["signType"] = "MD5"
	paySign := GetPaySign(d, PayKey)
	var signModel SignModel
	signModel.Appid = AppId
	signModel.NonceStr = nowTimeStr
	signModel.Package = "prepay_id=" + xmlResp.Prepay_id
	signModel.SignType = "MD5"
	signModel.Signature = paySign
	signModel.TimeStamp = timeStamp
	this.Data["json"] = map[string]interface{}{"data": signModel}
	this.ServeJSON()
}

// @Summary	公众号支付回调
func (this *PayController) JsApiPayCallBack() {
	defer this.Ctx.WriteString("<xml><return_code><![CDATA[SUCCESS]]></return_code><return_msg><![CDATA[OK]]></return_msg></xml>")
	body := this.Ctx.Input.RequestBody
	status, el := CheckMsgSign(string(body), PayKey)
	if status {
		resultCode := el.Node("result_code").Value
		if resultCode == "SUCCESS" {
			//支付成功后的业务逻辑
		}
	}
}

// @Summary 扫码充值
// @Description  带*参数必传
func (this *PayController) WxNative() {
	//请求UnifiedOrder的代码
	var yourReq UnifyOrderReq
	yourReq.Appid = AppId //微信开放平台我们创建出来的app的app id
	yourReq.Body = "标题"
	yourReq.Mch_id = MerId
	yourReq.Nonce_str = strconv.FormatInt(time.Now().Unix(), 10)
	yourReq.Notify_url = NativeUrl
	yourReq.Trade_type = "NATIVE"
	yourReq.Spbill_create_ip = SpbillCreateIp
	yourReq.Total_fee = 1             //单位是分，这里是1分钱
	yourReq.Out_trade_no = "12312312" //商户订单号
	m := make(map[string]interface{}, 0)
	m["appid"] = yourReq.Appid
	m["body"] = yourReq.Body
	m["mch_id"] = yourReq.Mch_id
	m["notify_url"] = yourReq.Notify_url
	m["trade_type"] = yourReq.Trade_type
	m["spbill_create_ip"] = yourReq.Spbill_create_ip
	m["total_fee"] = yourReq.Total_fee
	m["out_trade_no"] = yourReq.Out_trade_no
	m["nonce_str"] = yourReq.Nonce_str
	yourReq.Sign = WxpayCalcSign(m, PayKey) //这个是计算wxpay签名的函数上面已贴出
	bytes_req, err := xml.Marshal(yourReq)
	if err != nil {
		fmt.Println("以xml形式编码发送错误, 原因:", err)
		return
	}
	str_req := string(bytes_req)
	//wxpay的unifiedorder接口需要http body中xmldoc的根节点是<xml></xml>这种，所以这里需要replace一下
	str_req = strings.Replace(str_req, "UnifyOrderReq", "xml", -1)
	bytes_req = []byte(str_req)
	//发送unified order请求.
	req, err := http.NewRequest("POST", "https://api.mch.weixin.qq.com/pay/unifiedorder", bytes.NewReader(bytes_req))
	if err != nil {
		fmt.Println("New Http Request发生错误，原因:", err)
		return
	}
	req.Header.Set("Accept", "application/xml")
	//这里的http header的设置是必须设置的.
	req.Header.Set("Content-Type", "application/xml;charset=utf-8")
	c := http.Client{}
	resp, _err := c.Do(req)
	if _err != nil {
		fmt.Println("请求微信支付统一下单接口发送错误, 原因:", _err)
		return
	}
	xmlResp := UnifyOrderResp{}
	buf, _ := ioutil.ReadAll(resp.Body)
	_err = xml.Unmarshal(buf, &xmlResp)
	//处理return code.
	if xmlResp.Return_code == "FAIL" {
		fmt.Println("微信支付统一下单不成功，原因:", xmlResp.Return_msg)
		return
	}
	//这里已经得到微信支付的prepay id，需要返给客户端，由客户端继续完成支付流程
	fmt.Println("微信支付统一下单成功，预支付单号:", xmlResp.Prepay_id)
	fmt.Println("支付二维码：", xmlResp.Code_url)
	this.Data["json"] = map[string]interface{}{"data": xmlResp.Code_url}
	this.ServeJSON()

}

// @Summary 扫码支付回调
func (this *PayController) WxpayCallback() {
	w := this.Ctx.ResponseWriter
	r := this.Ctx.Request
	// body
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println("读取http body失败，原因!", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()
	fmt.Println("微信支付异步通知，HTTP Body:", string(body))
	var mr WXPayNotifyReq
	err = xml.Unmarshal(body, &mr)
	if err != nil {
		fmt.Println("解析HTTP Body格式到xml失败，原因!", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	var reqMap map[string]interface{}
	reqMap = make(map[string]interface{}, 0)
	reqMap["return_code"] = mr.Return_code
	reqMap["return_msg"] = mr.Return_msg
	reqMap["appid"] = mr.Appid
	reqMap["mch_id"] = mr.Mch_id
	reqMap["nonce_str"] = mr.Nonce
	reqMap["result_code"] = mr.Result_code
	reqMap["openid"] = mr.Openid
	reqMap["is_subscribe"] = mr.Is_subscribe
	reqMap["trade_type"] = mr.Trade_type
	reqMap["bank_type"] = mr.Bank_type
	reqMap["total_fee"] = mr.Total_fee
	reqMap["fee_type"] = mr.Fee_type
	reqMap["cash_fee"] = mr.Cash_fee
	reqMap["cash_fee_type"] = mr.Cash_fee_Type
	reqMap["transaction_id"] = mr.Transaction_id
	reqMap["out_trade_no"] = mr.Out_trade_no
	reqMap["attach"] = mr.Attach
	reqMap["time_end"] = mr.Time_end
	if mr.Coupon_fee > 0 {
		reqMap["coupon_fee"] = mr.Coupon_fee
		reqMap["coupon_count"] = mr.Coupon_count
		reqMap["coupon_fee_0"] = mr.Coupon_fee_0
		reqMap["coupon_id_0"] = mr.Coupon_id_0
	}
	var resp WXPayNotifyResp
	//进行签名校验
	if WxpayVerifySign(reqMap, mr.Sign) {
		//这里就可以更新我们的后台数据库了，其他业务逻辑同理。

	} else {
		resp.Return_code = "FAIL"
		resp.Return_msg = "failed to verify sign, please retry!"
	}
	//结果返回，微信要求如果成功需要返回return_code "SUCCESS"
	bytes, _err := xml.Marshal(resp)
	strResp := strings.Replace(string(bytes), "WXPayNotifyResp", "xml", -1)
	if _err != nil {
		fmt.Println("xml编码失败，原因：", _err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, strResp)
}

const (
	TRANSFERURL    = "https://api.mch.weixin.qq.com/mmpaymkttransfers/promotion/transfers"
	WECHATCERTPATH = "/usr/cert/apiclient_cert.pem" //客户端证书存放绝对路径
	WECHATKEYPATH  = "/usr/cert/apiclient_key.pem"  //客户端私匙存放绝对路径
	WECHATCAPATH   = "/usr/cert/rootca.pem"         //服务端证书存放绝对路径
)

//首先定义一个UnifyOrderReq用于填入我们要传入的参数。
type UnifyOrderReq struct {
	Appid            string `xml:"appid"`
	Body             string `xml:"body"`
	Mch_id           string `xml:"mch_id"`
	Nonce_str        string `xml:"nonce_str"`
	Notify_url       string `xml:"notify_url"`
	Trade_type       string `xml:"trade_type"`
	Spbill_create_ip string `xml:"spbill_create_ip"`
	Total_fee        int    `xml:"total_fee"`
	Out_trade_no     string `xml:"out_trade_no"`
	Sign             string `xml:"sign"`
	OpenId           string `xml:"openid"`
}

//支付通知req
type WXPayNotifyReq struct {
	Return_code    string `xml:"return_code"`
	Return_msg     string `xml:"return_msg"`
	Appid          string `xml:"appid"`
	Mch_id         string `xml:"mch_id"`
	Nonce          string `xml:"nonce_str"`
	Sign           string `xml:"sign"`
	Result_code    string `xml:"result_code"`
	Openid         string `xml:"openid"`
	Is_subscribe   string `xml:"is_subscribe"`
	Trade_type     string `xml:"trade_type"`
	Bank_type      string `xml:"bank_type"`
	Total_fee      int    `xml:"total_fee"`
	Fee_type       string `xml:"fee_type"`
	Cash_fee       int    `xml:"cash_fee"`
	Cash_fee_Type  string `xml:"cash_fee_type"`
	Transaction_id string `xml:"transaction_id"`
	Out_trade_no   string `xml:"out_trade_no"`
	Attach         string `xml:"attach"`
	Time_end       string `xml:"time_end"`
	Coupon_fee     int    `xml:"coupon_fee"`
	Coupon_count   int    `xml:"coupon_count"`
	Coupon_fee_0   int    `xml:"coupon_fee_0"`
	Coupon_id_0    string `xml:"coupon_id_0"`
}

//支付通知resp
type WXPayNotifyResp struct {
	Return_code string `xml:"return_code"`
	Return_msg  string `xml:"return_msg"`
}
type UnifyOrderResp struct {
	Return_code string `xml:"return_code"`
	Return_msg  string `xml:"return_msg"`
	Appid       string `xml:"appid"`
	Mch_id      string `xml:"mch_id"`
	Nonce_str   string `xml:"nonce_str"`
	Sign        string `xml:"sign"`
	Result_code string `xml:"result_code"`
	Prepay_id   string `xml:"prepay_id"`
	Trade_type  string `xml:"trade_type"`
	Code_url    string `xml:"code_url"`
}

//微信支付签名验证函数
func WxpayVerifySign(needVerifyM map[string]interface{}, sign string) bool {
	signCalc := WxpayCalcSign(needVerifyM, PayKey)
	if sign == signCalc {
		return true
	}

	return false
}

//微信支付计算签名的函数
func WxpayCalcSign(mReq map[string]interface{}, key string) (sign string) {
	//STEP 1, 对key进行升序排序.
	sorted_keys := make([]string, 0)
	for k, _ := range mReq {
		sorted_keys = append(sorted_keys, k)
	}

	sort.Strings(sorted_keys)

	//STEP2, 对key=value的键值对用&连接起来，略过空值
	var signStrings string
	for _, k := range sorted_keys {
		value := fmt.Sprintf("%v", mReq[k])
		if value != "" {
			signStrings = signStrings + k + "=" + value + "&"
		}
	}

	//STEP3, 在键值对的最后加上key=API_KEY
	if key != "" {
		signStrings = signStrings + "key=" + key
	}

	//STEP4, 进行MD5签名并且将所有字符转为大写.
	md5Ctx := md5.New()
	md5Ctx.Write([]byte(signStrings))
	cipherStr := md5Ctx.Sum(nil)
	upperSign := strings.ToUpper(hex.EncodeToString(cipherStr))
	return upperSign
}

//微信支付 下单签名
func GetPaySign(mReq map[string]interface{}, key string) string {
	sorted_keys := make([]string, 0)
	for k, _ := range mReq {
		sorted_keys = append(sorted_keys, k)
	}
	sort.Strings(sorted_keys)
	var signStrings string
	for _, k := range sorted_keys {
		value := fmt.Sprintf("%v", mReq[k])
		if value != "" {
			signStrings = signStrings + k + "=" + value + "&"
		}
	}
	if key != "" {
		signStrings = signStrings + "key=" + key
	}
	md5Ctx := md5.New()
	md5Ctx.Write([]byte(signStrings))
	cipherStr := md5Ctx.Sum(nil)
	upperSign := strings.ToUpper(hex.EncodeToString(cipherStr))
	return upperSign
}

//验证回调签名
func CheckMsgSign(xmlStr string, key string) (bool, *Element) {
	el, err := LoadByXml(xmlStr)
	if err != nil {
		return false, nil
	}
	sign := el.Node("sign").Value
	el.RemoveNode("sign")
	nodes := el.AllNodes()
	var c map[string]interface{}
	c = make(map[string]interface{}, 0)
	for i := 0; i < len(nodes); i++ {
		value := nodes[i].Value
		name := nodes[i].Name()
		c[name] = value
	}
	checkSign := GetPaySign(c, key)
	if checkSign == sign {
		return true, el
	}
	return false, nil
}

var _tlsConfig *tls.Config

func getTLSConfig() (*tls.Config, error) {
	if _tlsConfig != nil {
		return _tlsConfig, nil
	}

	// load cert
	cert, err := tls.LoadX509KeyPair(WECHATCERTPATH, WECHATKEYPATH)
	if err != nil {
		return nil, err
	}

	// load root ca
	caData, err := ioutil.ReadFile(WECHATCAPATH)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caData)

	_tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
	}
	return _tlsConfig, nil
}

func SecurePost(url string, xmlContent []byte) (*http.Response, error) {
	tlsConfig, err := getTLSConfig()
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: tr}

	return client.Post(
		url,
		"text/xml",
		bytes.NewBuffer(xmlContent))
}

func str2sha1(data string) string {
	t := sha1.New()
	io.WriteString(t, data)
	return fmt.Sprintf("%x", t.Sum(nil))
}
