package sn.foad.pocsecurityjwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import sn.foad.pocsecurityjwt.entities.PocRoles;

public interface PocRolesRepository extends JpaRepository<PocRoles, Long> {
    PocRoles findByRoleName(String roleName);

}
