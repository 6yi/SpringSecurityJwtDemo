package com.lzheng.jdbc_jwt.domain;

import java.io.Serializable;
import lombok.Data;

/**
 * roles
 * @author 
 */
@Data
public class Roles implements Serializable {
    private String username;

    private String role;

    private static final long serialVersionUID = 1L;
}