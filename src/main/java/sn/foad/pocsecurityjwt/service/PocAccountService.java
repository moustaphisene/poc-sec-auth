package sn.foad.pocsecurityjwt.service;

import sn.foad.pocsecurityjwt.entities.PocRoles;
import sn.foad.pocsecurityjwt.entities.PocUsers;

import java.util.List;


public interface PocAccountService {
    PocUsers addUser(PocUsers pocUsers);
    PocRoles addRole(PocRoles pocRoles);
    void addRoleToUser(String username, String roleName);
    PocUsers loadUserByUsername(String username);
    List<PocUsers> listUsers();
}
