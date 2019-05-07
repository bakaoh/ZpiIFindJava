# ZPI IFIND JAVA

## Usage

Decrypt and verify data to get user info

```java
import com.bakaoh.zpi.ZpiIFind;
...

String data = "get from query param `d`";
RSAPrivateKey receiverPrivate = ZpiIFind.getPrivateKey("ifind/private.pkcs8.pem");
RSAPublicKey senderPublic = ZpiIFind.getPublicKey("zpi/public.pkcs8.pem");

String message = ZpiIFind.decryptAndVerify(data, receiverPrivate, senderPublic);

...
```

## Note

Convert key file from [pkcs1 to pkcs8](https://blog.ndpar.com/2017/04/17/p1-p8/):
```
$ openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in private.pem -out private.pkcs8.pem 
$ openssl rsa -RSAPublicKey_in -in public.pem -pubout > public.pkcs8.pem
```
