package test.test.dto;

import lombok.Data;

@Data
public class UserDto {
	public UserDto(String username) {
		this.username = username;
	}

	private String username;
}
