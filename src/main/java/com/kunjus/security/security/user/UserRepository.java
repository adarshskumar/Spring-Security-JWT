package com.kunjus.security.security.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Integer> {

    //Method to find user by email
    //Optional --> used to deal with null values,helping to reduce occurrence of null pointer exceptions.
    Optional<User> findByEmail(String email);
}
