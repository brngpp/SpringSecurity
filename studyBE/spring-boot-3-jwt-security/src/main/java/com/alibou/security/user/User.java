package com.alibou.security.user;

import com.alibou.security.token.Token;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import java.util.Collection;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Data //lombok get ,set , toString ,equal and hashcode
@Builder // costruisce l oggetto con il design pattern builder 
@NoArgsConstructor //costruttore senza argomenti 
@AllArgsConstructor // costruttore con argomenti 
@Entity  //bean che ci dice che la classe è un entita
@Table(name = "_user") //tabella a cui si lega la classe nel db usiamo _user perchè user è già riservato nel db
public class User implements UserDetails {

  @Id             // Ogni entità ha una primary ID un campo con cui riconoscerlo 
  @GeneratedValue // generiamo automaticamente l id , in questo caso in maniera incrementare
  private Integer id;
  private String firstname;
  private String lastname;
  private String email;
  private String password;

  @Enumerated(EnumType.STRING)//i ruoli possibili nell app con enumType invece di avere 0,1,2 avremo le stringhe
  private Role role;

  @OneToMany(mappedBy = "user")
  private List<Token> tokens;

  @Override //ritorna la lista dei ruoli ricoperti da quell utente nell app
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return role.getAuthorities();
  }

  @Override
  public String getPassword() {
    return password;
  }

  @Override 
  public String getUsername() {
    return email;
  }

  @Override // l account è valido
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override // l account non è bloccato
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override // le credenziali sono validi 
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override //utente abilitato 
  public boolean isEnabled() {
    return true;
  }
}
