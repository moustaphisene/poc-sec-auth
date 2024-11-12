package sn.foad.pocsecurityjwt.service;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import sn.foad.pocsecurityjwt.entities.PocUsers;

import java.util.ArrayList;
import java.util.List;
@Service
public class PocUserDetailsServiceImpl implements UserDetailsService {
    private PocAccountService pocAccountService;

    public PocUserDetailsServiceImpl(PocAccountService pocAccountService) {
        this.pocAccountService = pocAccountService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        PocUsers pocUsers = pocAccountService.loadUserByUsername(username);
        List<GrantedAuthority> authorities = new ArrayList<>();
        pocUsers.getPocRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role.getRoleName()));
        });
        return new User(pocUsers.getUsername(), pocUsers.getPassword(), authorities);

    }

}
