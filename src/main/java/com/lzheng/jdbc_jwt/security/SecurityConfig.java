package com.lzheng.jdbc_jwt.security;

import com.lzheng.jdbc_jwt.security.filter.JwtFilter;
import com.lzheng.jdbc_jwt.security.filter.JwtLoginFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * @ClassName SecurityConfig
 * @Author 6yi
 * @Date 2020/6/21 14:09
 * @Version 1.0
 * @Description:
 */

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/admin/**").hasRole("admin")
                .antMatchers("/guest/**").hasRole("guest")
                .antMatchers(HttpMethod.POST, "/login").permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .addFilterAfter(new JwtLoginFilter("/login",authenticationManager()), UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(new JwtFilter(),JwtLoginFilter.class)
                .csrf().disable();
    }


    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

}
