const { PrismaClient } = require('./src/generated/prisma');
const p = new PrismaClient();
p.magicLink.findMany({ orderBy: { createdAt: 'desc' }, take: 3, select: { token: true, email: true, used: true, expiresAt: true } })
  .then(r => { console.log(JSON.stringify(r, null, 2)); p.$disconnect(); })
  .catch(e => { console.error(e); p.$disconnect(); });
