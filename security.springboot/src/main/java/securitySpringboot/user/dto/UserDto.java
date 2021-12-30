package securitySpringboot.user.dto;


import lombok.Builder;
import lombok.Data;

@Data
public class UserDto {

    private String userName;
    private String password;
    private String userEmail;

    @Builder
    public UserDto(String userName, String password, String userEmail) {
        this.userName = userName;
        this.password = password;
        this.userEmail = userEmail;
    }
}
