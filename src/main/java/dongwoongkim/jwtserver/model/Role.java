package dongwoongkim.jwtserver.model;


import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

@RequiredArgsConstructor
public enum Role implements GrantedAuthority {
    USER("ROLE_USER"), ADMIN("ROLE_ADMIN"), MANAGER("ROLE_MANAGER");
    private final String value;

    @Override
    public String getAuthority() {
        return this.value;
    }
}
