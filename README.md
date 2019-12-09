# android-security
## AndroidKeyStore加密保存敏感信息

#### 快速配置
```java
implementation 'de.yellowhing.security:security:0.0.4'
```

### 使用说明
##### 1、小数据量加密（100多byte以内）
```java
String dataStr = "abcdefg12222";
byte[] dataByte = dataStr.getBytes();
//加密使用默认密钥别名
String encryptData0 = AndroidCrypt.encrypt(data)

//加密使用指定密钥别名
byte[] encryptData1 = AndroidCrypt.encrypt(dataByte, "key_name")

//解密使用默认密钥别名
String encryptData2 = AndroidCrypt.decrypt(encryptData0)

//解密使用指定密钥别名
byte[] encryptData3 = AndroidCrypt.encrypt(encryptData1, "key_name")
```
##### 2、大数据量加密 
```java
String dataStr = "abcdefg...12222";
byte[] dataByte = dataStr.getBytes();
//加密使用默认密钥别名
String encryptData0 = AndroidCrypt.encryptByTls(data)

//加密使用指定密钥别名
byte[] encryptData1 = AndroidCrypt.encryptByTls(dataByte, "key_name")

//解密使用默认密钥别名
String encryptData2 = AndroidCrypt.decryptByTls(encryptData0)

//解密使用指定密钥别名
byte[] encryptData3 = AndroidCrypt.encryptByTls(encryptData1, "key_name")
```
<p>加密方式说明：大数据加密，先随机生成个对称密钥，使用对称密钥对数据进行加密，再用androidkeystore密钥生成的非对称密钥对随机生成的对称密钥加密，解密时，先解密出对称密钥，再使用对称密钥，解密数据。</p>

