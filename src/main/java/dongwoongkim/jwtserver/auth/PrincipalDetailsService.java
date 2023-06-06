package dongwoongkim.jwtserver.auth;

import dongwoongkim.jwtserver.model.User;
import dongwoongkim.jwtserver.repo.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

// http://localhost:8080/login
@Slf4j
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("PrincipalDetailsService Execute!");
        Optional<User> userEntity = userRepository.findByUsername(username);
        if (userEntity.isPresent()) {
            return new PrincipalDetails(userEntity.get());
        }
        return null;
    }
}
