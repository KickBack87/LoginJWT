package br.com.arq.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Entity
@Table(name = "usuario")
public class Usuario implements Serializable {

	
	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long idUsuario;
	
	@Column(length = 50)
	@Size(min = 3, message = "O nome deve ter no minimo 3 letras")
	@NotNull
	private String nomeUsuario;
	
	@Column(length = 50, unique = true)
    @Email(message = "Email esta fora do padrao")
	@NotNull
	private String loginUsuario;
	
	@Column(length = 30)
	@Size(min = 6, message = "A senha esta fora do padrao")
	@NotNull
	private String senhaUsuario;

	public Long getIdUsuario() {
		return idUsuario;
	}

	public void setIdUsuario(Long idUsuario) {
		this.idUsuario = idUsuario;
	}

	public String getNomeUsuario() {
		return nomeUsuario;
	}

	public void setNomeUsuario(String nomeUsuario) {
		this.nomeUsuario = nomeUsuario;
	}

	public String getLoginUsuario() {
		return loginUsuario;
	}

	public void setLoginUsuario(String loginUsuario) {
		this.loginUsuario = loginUsuario;
	}

	public String getSenhaUsuario() {
		return senhaUsuario;
	}

	public void setSenhaUsuario(String senhaUsuario) {
		this.senhaUsuario = senhaUsuario;
	}

	public static long getSerialversionuid() {
		return serialVersionUID;
	}

	public Usuario() {
		super();
	}

	@Override
	public String toString() {
		return "Usuario [idUsuario=" + idUsuario + ", nomeUsuario=" + nomeUsuario + ", loginUsuario=" + loginUsuario
				+ "]";
	}

	public Usuario(Long idUsuario, @Size(min = 3, message = "O nome deve ter no minimo 3 letras") String nomeUsuario,
			String loginUsuario, @Size(min = 6, message = "A senha esta fora do padrao") String senhaUsuario) {
		super();
		this.idUsuario = idUsuario;
		this.nomeUsuario = nomeUsuario;
		this.loginUsuario = loginUsuario;
		this.senhaUsuario = senhaUsuario;
	}

	public Usuario(Long idUsuario, @Size(min = 3, message = "O nome deve ter no minimo 3 letras") String nomeUsuario,
			String loginUsuario) {
		super();
		this.idUsuario = idUsuario;
		this.nomeUsuario = nomeUsuario;
		this.loginUsuario = loginUsuario;
	}
	
	
	
}
