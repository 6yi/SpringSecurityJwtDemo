package com.lzheng.jdbc_jwt;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan("com.lzheng.jdbc_jwt.dao")
public class JdbcJwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(JdbcJwtApplication.class, args);
    }

}
