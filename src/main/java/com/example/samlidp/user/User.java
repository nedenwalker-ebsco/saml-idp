package com.example.samlidp.user;

import java.io.Serializable;
import java.util.List;

public class User implements Serializable {

  private static final long serialVersionUID = 1L;
  private String name;
  private String password;
  private List<String> authorities;

  public User(String name, String password, List<String> authorities) {
    super();
    this.name = name;
    this.password = password;
    this.authorities = authorities;
  }

  public String getName() {
    return name;
  }
  public String getPassword() {
    return password;
  }
  public List<String> getAuthorities() {
    return authorities;
  }

  @Override
  public String toString() {
    return "User [name=" + name + ", password=" + password + ", authorities=" + authorities + "]";
  }

}
