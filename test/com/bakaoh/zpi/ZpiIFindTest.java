package com.bakaoh.zpi;


import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import static org.junit.jupiter.api.Assertions.*;

class ZpiIFindTest {

    String data = "h18XD8D94yz4RCYcXLpARbL1aVSJk4cEwtZerrVNxubs333E9GHH14DQc2QaVH7NDuSMaoFMBg1qtx5m5C8aNnBTmh4oQgv5CMLyNJjDzmpP7e94DqhUsHzLdwR3C2VDAir7TWmM5asxa3ABwZtm3xhp6Fh7ut4GNdbHjyKAegD4N2LgdrUSfjR5cr9wRTCr3mry6gkRfjS2vtgJTQj2GM63KeEWY4uBKAEYjB8JXHbq3JDCUUtxox9psEKjUqx4yYj5v3rqmWtNn7emt8m2CNJapr6Efb6N7cHUmSfVLyELV5zY9UgwGzh38hW8KUNS2HeJF1Y6Mt9FT1EjZRbHQHvYLJUo7rF2EnBWXxWpL9tt1tTMrVb7K5XAMWSZJa1kiPVQVXCG4odGSRgXF3jTxpm7Re744SVFoQbt5nyLxk2HCmKtKP8WGzxygyEo9J5QTBLPWPLCCYKA8RANhKBjrjmkkTDgBMi4AC7X2wyhAAGF5xgH5DXCMgifkzyQLUFJeq5n1FUsPfi1dnGWVUukgvuxDN8Vx5N5fqMGR7KNeJPdFU4AkK4DcstW81gKHUNssTmxJS9VjK6KutC5Paxx1npAZmKUvZkXdzirpjV9S7Emt3QdgG8arF6dqPwQM2QQifNCC2hopVQumFWJy9eN7dPLSF1mg2V5LiTdCWg3SrjAdTkUQgFcuY7cMfF_2k7Kx7E8QNAMXjxbxReS6128UZB3bjhdVVYJXyT25RdQX6mnZXyhtb4XAQeZt2aKgHnStYULQtFxdFMwvccQRoiLB7cgv9isMk9raMCFbJBnz4aNhsmrvUGFMAbeg1WvYs34f3EJxMde2GNUB2cuKKhtvD374zdtnUB856UaqBfK6YLx8ouFWuFk24FVAMigMC1bCrgY85HFLB2fkQmw4tDVCKj88ZoQT2R5EBGLnnSCLHE547BCgfxPgY7TkJnFFf1ZSsfkwark44Z7agjKim4Ws5LQabR3h1NxmrpZG4Add4xxHuwtLD1Sy8uJLZxzaJrkYZhhzGMrYbq2dYiNqXdyYuDSeB";
    String message = "{\"phone\":\"0966333444\",\"expired_time\":1555661758}";

    RSAPrivateKey receiverPrivate;
    RSAPublicKey senderPublic;

    @org.junit.jupiter.api.BeforeEach
    void setUp() throws Exception {
        receiverPrivate = ZpiIFind.getPrivateKey("ifind/private.pkcs8.pem");
        senderPublic = ZpiIFind.getPublicKey("zpi/public.pkcs8.pem");
    }

    @org.junit.jupiter.api.Test
    void decryptAndVerify() throws Exception {
        assertEquals(message, ZpiIFind.decryptAndVerify(data, receiverPrivate, senderPublic));
    }
}