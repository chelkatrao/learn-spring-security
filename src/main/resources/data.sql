insert into t_user(id, c_username)
values (1, 'chelkatrao');
insert into t_user_password(id_user, c_password)
values (1, '{noop}chelkatrao');
insert into t_user_authority(id_user, c_authority)
values (1, 'ROLE_DB_USER');