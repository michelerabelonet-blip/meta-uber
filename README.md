# Meta Uber
App (PWA) para controlar ganhos no Uber/99: lançamento diário, lucro livre do mês e quanto falta para a meta.

- **Servidor:** Node/Express (`server.js`), arquivos do app em `public/`.
- **Banco:** Postgres (Supabase). Configure a variável `DATABASE_URL` com a connection string do **Session pooler** do Supabase. As tabelas (`mu_config`, `mu_dias`) são criadas automaticamente.
- **Acesso:** PIN de 4 a 8 números, criado no primeiro acesso (guardado com hash). Trocar o PIN desconecta os outros aparelhos.
- **Sem banco:** o app continua funcionando e salva só no aparelho.

Render: Web Service, build `npm install`, start `npm start`, health check `/saude`.
