package com.lzheng.jdbc_jwt.dao;

import com.lzheng.jdbc_jwt.domain.Roles;

import java.util.List;

public interface RolesDao {
    int insert(Roles record);

    int insertSelective(Roles record);

    List<Roles> selectByUserName(String userName);
}