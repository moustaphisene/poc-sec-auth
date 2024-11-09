package sn.foad.pocsecurityjwt;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import sn.foad.pocsecurityjwt.entities.PocRoles;
import sn.foad.pocsecurityjwt.entities.PocUsers;
import sn.foad.pocsecurityjwt.service.PocAccountService;

import java.util.ArrayList;
import java.util.HashSet;

@SpringBootApplication
public class PocSecurityJwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(PocSecurityJwtApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder (){
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner start(PocAccountService pocAccountService) {
        return args -> {
            pocAccountService.addRole(new PocRoles(null,"USER"));
            pocAccountService.addRole(new PocRoles(null,"ADMIN"));
            pocAccountService.addRole(new PocRoles(null,"SUPERVISOR"));
            pocAccountService.addRole(new PocRoles(null,"ACCOUNTING"));

            pocAccountService.addUser(new PocUsers(null,"farba","passer",new HashSet<>()));
            pocAccountService.addUser(new PocUsers(null,"bamba","passer",new HashSet<>()));
            pocAccountService.addUser(new PocUsers(null,"admin","passer",new HashSet<>()));
            pocAccountService.addUser(new PocUsers(null,"mareme","passer",new HashSet<>()));
            pocAccountService.addUser(new PocUsers(null,"bassirou","passer",new HashSet<>()));

            pocAccountService.addRoleToUser("farba","USER");
            pocAccountService.addRoleToUser("bamba","USER");
            pocAccountService.addRoleToUser("admin","USER");
            pocAccountService.addRoleToUser("admin","ADMIN");
            pocAccountService.addRoleToUser("bassirou","USER");
            pocAccountService.addRoleToUser("bassirou","SUPERVISOR");
            pocAccountService.addRoleToUser("mareme","USER");
            pocAccountService.addRoleToUser("mareme","ACCOUNTING");

        };
    }

}
