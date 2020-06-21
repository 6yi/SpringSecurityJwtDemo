package com.lzheng.jdbc_jwt.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @ClassName HelloController
 * @Author 6yi
 * @Date 2020/6/21 14:15
 * @Version 1.0
 * @Description:
 */

@RestController
public class HelloController {
    @GetMapping("/hello")
    public String hello(){
        return "hello";
    }

    @GetMapping("/admin/api")
    public String admin() {
        return"hello admin !";
    }

    @GetMapping("/guest")
    public String guest() {
        return"hello guest !";
    }

}
