using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using RpgApi.Data;
using RpgApi.Models;
using RpgApi.Utils;

namespace RpgApi.Controllers
{
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class UsuariosController : ControllerBase
    {
        private readonly DataContext _context;

        private readonly IConfiguration _configuration;

        public UsuariosController(DataContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        private string CriarToken(Usuario usuario)
        {
        List<Claim> claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, usuario.Id.ToString()),
            new Claim(ClaimTypes.Name, usuario.Username)
        };
            SymmetricSecurityKey key = new SymmetricSecurityKey(Encoding.UTF8
            .GetBytes(_configuration.GetSection("ConfiguracaoToken:Chave").Value));
            SigningCredentials creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.Now.AddDays(1),
            SigningCredentials = creds
        };
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private async Task<bool> UsuarioExistente(string username)
        {
            if (await _context.TB_USUARIOS.AnyAsync(x => x.Username.ToLower() == username.ToLower()))
            {
                return true;
            }

            return false;
        }

        [AllowAnonymous]
        [HttpPost("Registrar")]
        public async Task<IActionResult> RegistrarUsuario(Usuario user)
        {
            try
            {
                if (await UsuarioExistente(user.Username))
                    throw new System.Exception("Nome de usuário já existe");
                Criptografia.CriarPasswordHash(user.PasswordString, out byte[] hash, out byte[] salt);
                user.PasswordString = string.Empty;
                user.PasswordHash = hash;
                user.PasswordSalt = salt;
                await _context.TB_USUARIOS.AddAsync(user);
                await _context.SaveChangesAsync();
                return Ok(user.Id);
            }
            catch (System.Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [AllowAnonymous]
        [HttpPost("Autenticar")]
        public async Task<IActionResult> AutenticarUsuario(Usuario credenciais)
        {
            try
            {
                Usuario? usuario = await _context.TB_USUARIOS.FirstOrDefaultAsync(x => x.Username.ToLower().Equals(credenciais.Username.ToLower()));

                if (usuario == null)
                {
                    throw new System.Exception("Usuário não encontrado.");
                }

                else if (!Criptografia.VerificarPasswordHash(credenciais.PasswordString, usuario.PasswordHash, usuario.PasswordSalt))
                {
                    throw new System.Exception("Senha incorreta.");
                }
                else
                {
                    //3-----
                    usuario.DataAcesso = DateTime.Now;
                    _context.TB_USUARIOS.Update(usuario);
                    await _context.SaveChangesAsync();

                    usuario.PasswordHash = null;
                    usuario.PasswordSalt = null;
                    usuario.Token = CriarToken(usuario);
                    return Ok(usuario);
                }
            }
            catch (System.Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        //Exercicios-----------------------------

        //1
        [HttpPut("AlterarSenha")]
        public async Task<IActionResult> AlterarSenha(Usuario usuario)
        {
            try
            {
                Usuario? usuarioAchado = await _context.TB_USUARIOS.FirstOrDefaultAsync(u => u.Id == usuario.Id);
                if (usuario == null)
                {
                    return NotFound("Usuário não encontrado.");
                }

                Criptografia.CriarPasswordHash(usuario.PasswordString, out byte[] hash, out byte[] salt);
                usuario.PasswordHash = hash;
                usuario.PasswordSalt = salt;

                _context.TB_USUARIOS.Update(usuario);
                await _context.SaveChangesAsync();

                return Ok("Senha alterada com sucesso.");
            }
            catch (System.Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        //2
        [HttpGet]
        public async Task<IActionResult> GetUsuarios()
        {
            try
            {
                List<Usuario> usuarios = await _context.TB_USUARIOS.ToListAsync();
                if (usuarios == null || usuarios.Count == 0)
                {
                    return NotFound("Nenhum.");
                }
                return Ok(usuarios);
            }
            catch (System.Exception ex)
            {
                return BadRequest(ex.Message + " - " + ex.InnerException);
            }
        }
        
        


    }
}
