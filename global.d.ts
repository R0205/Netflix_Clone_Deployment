import { PrismaClient } from '@prisma/client';
import { MongoClient } from 'mongodb';

declare global {
  namespace globalThis {
    var prismadb: PrismaClient
  }
}