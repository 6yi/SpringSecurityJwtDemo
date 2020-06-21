package com.lzheng.jdbc_jwt.dao;

import com.lzheng.jdbc_jwt.domain.User;

public interface UserDao {
    int insert(User record);

    int insertSelective(User record);

    User selectByUserName(String userName);

}