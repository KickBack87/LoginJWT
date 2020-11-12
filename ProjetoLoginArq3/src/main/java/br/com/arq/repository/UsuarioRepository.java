package br.com.arq.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import br.com.arq.entity.Usuario;

public interface UsuarioRepository extends JpaRepository<Usuario, Long>{
	
	

}
