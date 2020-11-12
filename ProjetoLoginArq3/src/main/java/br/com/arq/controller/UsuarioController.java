package br.com.arq.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.com.arq.entity.Usuario;
import br.com.arq.repository.UsuarioRepository;

@RestController
public class UsuarioController {
	
	
	@Autowired
	UsuarioRepository repositorydao;
	
	
	@GetMapping("/usuario")
	public List<Usuario> findAll() {
	return repositorydao.findAll();
	}
	
	@PostMapping(value = "/usuario", consumes =
			MediaType.APPLICATION_JSON_VALUE, produces =
			MediaType.APPLICATION_JSON_VALUE)
			public ResponseEntity<?> salvar(@RequestBody Usuario
			usuario) {
			try {
				repositorydao.save(usuario);
				
				return ResponseEntity.ok(usuario);
				} catch (Exception ex) {
				
				return new ResponseEntity<String>("nao gravado no banco",
				HttpStatus.BAD_REQUEST);
				}
			
				}
	
	
	
	
	@RequestMapping("/home")
	public String hello() {
		return "Hello buddy!";
	}
	
	
	
	@GetMapping("/usuario/{id}")
	public ResponseEntity<?> getUsuarioId(@PathVariable("id")
	Long id) {
	try {
	Usuario usuario = repositorydao.findById(id).get();
	if (usuario == null) {
	throw new Exception("Id nao Encontrado");
	}
	return new ResponseEntity<Usuario>(usuario,
	HttpStatus.OK);
	} catch (Exception ex) {
	Map<String, String> mapa = new HashMap<String, String>();
	mapa.put("error", ex.getMessage());
	return new
	ResponseEntity<String>(mapa.toString(), HttpStatus.CONFLICT);
	}
	}
	
	
	
	
}
