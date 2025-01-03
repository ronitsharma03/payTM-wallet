import { Card } from "@repo/ui/card";

interface UserDetails {
    id: number;
    number: number;
    // name: string;
}
interface txnType {
  time: Date;
  amount: number;
  fromUser: UserDetails;
  toUser: UserDetails;
}
interface P2pTxnType {
  transactions: txnType[];
  currentUser: number;
}

export const P2pTransactions = ({
  transactions,
  currentUser,
}: P2pTxnType) => {
  if (!transactions.length) {
    return (
      <Card title="Recent Transactions">
        <div className="text-2xl font-semibold">No Recent Transactions</div>
      </Card>
    );
  }
  return (
    <div>
      <Card title="Recent Transactions">
        <div>
          {transactions.map((t) => {
            const isSent = Number(currentUser) === Number(t.fromUser.id);
            // console.log(currentUser)
            // console.log(t.fromUser)
            // console.log(Number(currentUser) == Number(t.toUser));
            // console.log(isSent) // Determine if the transaction was sent by the current user
            return (
              <div
                className="flex justify-between mt-2"
                key={t.time.toISOString()}
              >
                <div>
                  <div className="text-sm">
                    {isSent ? `To ${(t.toUser.number)}` : `From ${(t.fromUser.number)}`}{" "}
                    {/* Corrected the labels */}
                  </div>
                  <div className="text-slate-600 text-xs">
                    {new Date(t.time).toDateString()}
                  </div>
                </div>
                <div className="flex flex-col justify-center">
                  {isSent ? "- Rs " : "+ Rs "} {/* Corrected the signs */}
                  {t.amount / 100}
                </div>
              </div>
            );
          })}
        </div>
      </Card>
    </div>
  );
};
