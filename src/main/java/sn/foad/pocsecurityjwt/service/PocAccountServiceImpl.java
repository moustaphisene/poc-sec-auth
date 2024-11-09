package sn.foad.pocsecurityjwt.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import sn.foad.pocsecurityjwt.entities.PocRoles;
import sn.foad.pocsecurityjwt.entities.PocUsers;
import sn.foad.pocsecurityjwt.repository.PocRolesRepository;
import sn.foad.pocsecurityjwt.repository.PocUserRepository;

import java.util.List;

@Service
@Transactional
public class PocAccountServiceImpl implements PocAccountService {

    private PocUserRepository pocUserRepository;
    private PocRolesRepository pocRolesRepository;
    private PasswordEncoder passwordEncoder;

    public PocAccountServiceImpl(PocUserRepository pocUserRepository,
                                 PocRolesRepository pocRolesRepository,
                                 PasswordEncoder passwordEncoder) {
        this.pocUserRepository = pocUserRepository;
        this.pocRolesRepository = pocRolesRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public PocUsers addUser(PocUsers pocUsers) {
        String pass=pocUsers.getPassword();
        pocUsers.setPassword(passwordEncoder.encode(pass));
        return pocUserRepository.save(pocUsers);
    }

    @Override
    public PocRoles addRole(PocRoles pocRoles) {
        return pocRolesRepository.save(pocRoles);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        PocUsers pocUsers = pocUserRepository.findByUsername(username);
        PocRoles pocRoles = pocRolesRepository.findByRoleName(roleName);
        if (pocUsers == null) {
            throw new IllegalArgumentException("Utilisateur non trouvé avec le nom d'utilisateur : " + username);
        }
        if (pocRoles == null) {
            throw new IllegalArgumentException("Rôle non trouvé avec le nom de rôle : " + roleName);
        }
        pocUsers.getPocRoles().add(pocRoles);

    }

    @Override
    public PocUsers loadUserByUsername(String username) {
        return pocUserRepository.findByUsername(username);

    }

    @Override
    public List<PocUsers> listUsers() {
        return pocUserRepository.findAll();
    }
}
