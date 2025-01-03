import { getServerSession } from "next-auth";
import { authOptions } from "../../lib/auth";
import prisma from "@repo/db/client";
import { BalanceCard } from "../../../components/BalanceCard";
import { getBalance } from "../transfer/page";
import { P2pTransactions } from "../../../components/P2pTransactions";

async function getP2pTransactions() {
  const session = await getServerSession(authOptions);
  const userId = session?.user?.id;
  const txns = await prisma.p2pTransactions.findMany({
    where: {
      OR: [
        {
          fromUserId: Number(userId),
        },
        {
          toUserId: Number(userId),
        },
      ],
    },
    orderBy: {
      timestamp: "desc",
    },
    include: {
      fromUser: true,
      toUser: true,
    },
  });

  return txns.map((t) => ({
    time: t.timestamp,
    amount: t.amount,
    fromUser: {
      id: t.fromUserId,
      name: t.fromUser.name,
      number: Number(t.fromUser.number),
    },
    toUser: {
      id: t.toUserId,
      name: t.toUser.name,
      number: Number(t.toUser.number),
    },
  }));
}

async function currentUser() {
  const session = await getServerSession(authOptions);
  const userDetails = await prisma.user.findUnique({
    where: {
      id: Number(session?.user?.id),
    },
  });

  if (!userDetails) {
    return null;
  }

  return {
    email: userDetails.email,
    number: userDetails.number,
    name: userDetails.name,
  };
}

export default async function () {
  const balance = await getBalance();
  const transactions = await getP2pTransactions();
  const session = await getServerSession(authOptions);
  const currentUserId = session?.user?.id;
  //   console.log(currentUserId)
  return (
    <div className="w-full">
      <div className="text-4xl text-[#6a51a6] pt-8 mb-8 ml-4 font-bold">
        P2P Transactions
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 p-4">
        <div>
          <div>
            <BalanceCard amount={balance.amount} locked={balance.locked} />
          </div>
          <div className="pt-4">
            <P2pTransactions
              transactions={transactions}
              currentUser={Number(currentUserId)
              }
            />
          </div>
        </div>
      </div>
    </div>
  );
}
