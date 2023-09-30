import {prisma} from '@reynandaptr/aha-types/dist';
import moment from 'moment';

export const createUserWithGoogleAccount = async () => {
  await prisma.user.create({
    data: {
      email: 'reynandapp1997@yahoo.com',
      provider: 'GOOGLE',
      provider_id: '106210729166790193600',
      is_verified: true,
      name: '',
    },
  });
};

export const createUserSession = async () => {
  const user1 = await prisma.user.findFirstOrThrow({
    where: {
      email: 'reynandapp1997@gmail.com',
    },
  });
  const user2 = await prisma.user.findFirstOrThrow({
    where: {
      email: 'reynandapp1997@yahoo.com',
    },
  });
  let currentDate = moment();

  let last7Dates: string[] = [];

  for (let i = 0; i < 7; i++) {
    last7Dates.push(currentDate.format('YYYY-MM-DD'));
    currentDate = currentDate.subtract(1, 'days');
  }

  last7Dates = last7Dates.reverse();

  const createSessionPromises = (userID: number) => last7Dates.map(async (date, i) => {
    if (userID === user2.id && i === 0) {
      return null;
    }
    return prisma.session.create({
      data: {
        user_id: userID,
        created_at: moment(date + ' ' + moment().format('YYYY-MM-DD'), 'YYYY-MM-DD HH:mm:ss').toDate(),
        type: 'ONLINE',
      },
    });
  });

  await Promise.all([createSessionPromises(user1.id), createSessionPromises(user2.id)]);
};
