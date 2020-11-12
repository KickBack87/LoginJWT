package br.com.arq.config;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;

import br.com.arq.entity.Usuario;

// Interceptar as requisições do tipo POST feitas em /login e tentar autenticar o usuario

	public class JWTLoginFilter extends AbstractAuthenticationProcessingFilter {

		protected JWTLoginFilter(String url, AuthenticationManager authManager) {
			super(new AntPathRequestMatcher(url));
			setAuthenticationManager(authManager);
		}


		
		
		public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
				throws AuthenticationException, IOException, ServletException {
			
			Usuario u = new ObjectMapper()
					.readValue(request.getInputStream(), Usuario.class);
		
			return getAuthenticationManager().authenticate(
					new UsernamePasswordAuthenticationToken(
						u.getLoginUsuario(), u.getSenhaUsuario())
				);
	}
		
		@Override
		protected void successfulAuthentication(
				HttpServletRequest request, 
				HttpServletResponse response,
				FilterChain filterChain,
				Authentication auth) throws IOException, ServletException {
			
			TokenAuthenticationService.addAuthentication(response, auth.getName());
		}




		
		

	}