package com.cos.jwtex01.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.cos.jwtex01.model.User;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long>{
	User findByUsername(String username);
	@Query("SELECT u FROM User u WHERE u.username = :username")
	Optional<User> findByUsername2(@Param("username") String username);
}
