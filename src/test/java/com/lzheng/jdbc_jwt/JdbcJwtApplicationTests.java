package com.lzheng.jdbc_jwt;

import com.lzheng.jdbc_jwt.dao.UserDao;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootTest
class JdbcJwtApplicationTests {

    @Autowired
    UserDao userDao;
    @Test
    void contextLoads() {
        System.out.println(userDao.selectByUserName("lzheng"));

    }

}
