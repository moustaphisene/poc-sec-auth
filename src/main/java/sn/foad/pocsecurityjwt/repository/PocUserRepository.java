package sn.foad.pocsecurityjwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import sn.foad.pocsecurityjwt.entities.PocUsers;

public interface PocUserRepository extends JpaRepository <PocUsers,Long> {
    PocUsers findByUsername(String username);

}
