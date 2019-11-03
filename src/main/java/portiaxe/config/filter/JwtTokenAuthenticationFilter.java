package portiaxe.config.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

public class JwtTokenAuthenticationFilter extends  OncePerRequestFilter {

    private final Log logger = LogFactory.getLog(this.getClass());
   
    
	@Value("${jwt.secret}")
	private String secret;
	 

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		secret ="93$0n1V$3cr3T";
		logger.info("SECRET: "+secret);
		// 1. get the authentication header. Tokens are supposed to be passed in the authentication header
				String header = request.getHeader("Authorization");
				
				// 2. validate the header and check the prefix
				if(header == null || !header.startsWith("Bearer ")) {
					chain.doFilter(request, response);  		// If not valid, go to the next filter.
					return;
				}
				
				logger.info("Header: "+header);
				// If there is no token provided and hence the user won't be authenticated. 
				// It's Ok. Maybe the user accessing a public path or asking for a token.
				
				// All secured paths that needs a token are already defined and secured in config class.
				// And If user tried to access without access token, then he won't be authenticated and an exception will be thrown.
				
				// 3. Get the token
				String token = header.replace("Bearer ", "");
				logger.info("TOKEN: "+token);
				
				try {	// exceptions might be thrown in creating the claims if for example the token is expired
					
					// 4. Validate the token
					Claims claims = Jwts.parser()
							.setSigningKey(secret)
							.parseClaimsJws(token)
							.getBody();
					
					String username = claims.getSubject();
					
					logger.info("SUBJECT NAME: "+username);
					if(username != null) {
						@SuppressWarnings("unchecked")
						List<String> authorities = (List<String>) claims.get("authorities");
						
						logger.info("AUTHORITIES: "+authorities);
						// 5. Create auth object
						// UsernamePasswordAuthenticationToken: A built-in object, used by spring to represent the current authenticated / being authenticated user.
						// It needs a list of authorities, which has type of GrantedAuthority interface, where SimpleGrantedAuthority is an implementation of that interface
						
						
						UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
										 username, null, authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
						
						
//						 UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
//								 username, null, null);
				 
						 // 6. Authenticate the user
						 // Now, user is authenticated
						 SecurityContextHolder.getContext().setAuthentication(auth);
					}
					
				} catch (Exception e) {
					e.printStackTrace();
					// In case of failure. Make sure it's clear; so guarantee user won't be authenticated
					SecurityContextHolder.clearContext();
				}
				
				// go to the next filter in the filter chain
				chain.doFilter(request, response);
			}
}
