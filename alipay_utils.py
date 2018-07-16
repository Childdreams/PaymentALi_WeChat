# !/usr/bin/env python
# -*- coding: utf-8 -*-

from datetime import datetime, timedelta
import sys
import hashlib
import time
from models import *
import collections
import base64
from Crypto.PublicKey import RSA  # pip install pycrypto
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from urllib import quote_plus
import json
import logging
reload(sys)
sys.setdefaultencoding('utf8')


Appid = "2017071907810348"
method ="alipay.trade.app.pay"
sign_type = "RSA2"
version = "1.0"
public_key = """-----BEGIN PUBLIC KEY-----
#code
-----END PUBLIC KEY-----"""

private_key = """-----BEGIN RSA PRIVATE KEY-----
code
"""

class AliPay(object):
    """
    支付宝支付接口(APP端支付接口)
    """
    def __init__(self, app_notify_url=None,
                   debug=False):
        self.appid = Appid
        self.app_notify_url = app_notify_url
        self.app_private_key = RSA.importKey(private_key)
        self.alipay_public_key = RSA.importKey(public_key)

        if debug is True:
            self.__gateway = "https://openapi.alipaydev.com/gateway.do"
        else:
            self.__gateway = "https://openapi.alipay.com/gateway.do"

    def direct_pay(self, subject, out_trade_no, total_amount, return_url=None, **kwargs):
        biz_content = {
            "subject": subject,
            "out_trade_no": out_trade_no,
            "total_amount": total_amount,
            "product_code": "QUICK_MSECURITY_PAY",
        }

        biz_content.update(kwargs)
        data = self.build_body("alipay.trade.app.pay", biz_content)
        return self.sign_data(data)

    def build_body(self, method, biz_content, return_url=None):
        data = {
            "app_id": self.appid,
            "method": method,
            "charset": "utf-8",
            "sign_type": "RSA2",
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "version": "1.0",
            "biz_content": biz_content
        }
        data["notify_url"] = self.app_notify_url

        return data

    def sign_data(self, data):
        data.pop("sign", None)
        # 排序后的字符串
        unsigned_items = self.ordered_data(data)
        unsigned_string = "&".join("{0}={1}".format(k, v) for k, v in unsigned_items)
        sign = self.sign(unsigned_string.encode("utf-8"))
        # ordered_items = self.ordered_data(data)
        quoted_string = "&".join("{0}={1}".format(k, quote_plus(v)) for k, v in unsigned_items)

        # 获得最终的订单信息字符串
        signed_string = quoted_string + "&sign=" + quote_plus(sign)
        return signed_string

    def ordered_data(self, data):
        complex_keys = []
        for key, value in data.items():
            if isinstance(value, dict):
                complex_keys.append(key)

        # 将字典类型的数据dump出来
        for key in complex_keys:
            data[key] = json.dumps(data[key], separators=(',', ':'))

        return sorted([(k, v) for k, v in data.items()])

    def sign(self, unsigned_string):
        # 开始计算签名
        key = self.app_private_key
        signer = PKCS1_v1_5.new(key)
        signature = signer.sign(SHA256.new(unsigned_string))
        # base64 编码，转换为unicode表示并移除回车
        sign = base64.b64encode(signature).decode("utf8").replace("\n", "")
        return sign

    def _verify(self, raw_content, signature):
        # 开始计算签名
        key = self.alipay_public_key
        signer = PKCS1_v1_5.new(key)
        digest = SHA256.new()
        digest.update(raw_content.encode("utf8"))
        if signer.verify(digest, base64.b64decode(signature.encode("utf8"))):
            return True
        return False

    def verify(self, data, signature):
        if "sign_type" in data:
            sign_type = data.pop("sign_type")
        if "sign" in data:
            sign = data.pop("sign")
        # 排序后的字符串
        unsigned_items = self.ordered_data(data)
        message = "&".join(u"{}={}".format(k, v) for k, v in unsigned_items)
        return self._verify(message, signature)

