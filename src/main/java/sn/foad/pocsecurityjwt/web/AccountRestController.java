package sn.foad.pocsecurityjwt.web;


import lombok.Data;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import sn.foad.pocsecurityjwt.entities.PocRoles;
import sn.foad.pocsecurityjwt.entities.PocUsers;
import sn.foad.pocsecurityjwt.service.PocAccountService;

import java.util.List;

@RestController
public class AccountRestController {
    private PocAccountService accountService;
    public AccountRestController(PocAccountService pocAccountService) {
        this.accountService = pocAccountService;

    }

    @GetMapping(path = "/pocusers")
    @PostAuthorize("hasAnyAuthority('USER')")
    public List<PocUsers> pocUsers(){
        return accountService.listUsers();
    }

    @PostAuthorize("hasAnyAuthority('ADMIN')")
    @PostMapping(path = "/pocusers")
    public PocUsers saveUser(@RequestBody PocUsers pocUsers){
        return accountService.addUser(pocUsers);
    }

    @PostMapping(path = "/pocroles")
    @PostAuthorize("hasAnyAuthority('ADMIN')")
    public PocRoles saveRole(@RequestBody PocRoles pocRoles){
        return accountService.addRole(pocRoles);
    }

    @PostMapping(path = "/pocaddroles")
    @PostAuthorize("hasAnyAuthority('ADMIN')")
    public void addRoleToUser(@RequestBody RoleUserForm roleUserForm){
         accountService.addRoleToUser(roleUserForm.getUsername(),roleUserForm.getRoleName());
    }

}
@Data
class RoleUserForm{
    private String username;
    private String roleName;
}