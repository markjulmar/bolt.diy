import { type ActionFunctionArgs, type LoaderFunctionArgs } from '@remix-run/cloudflare';
import { logout } from '~/utils/session.server';

export async function action({ request }: ActionFunctionArgs) {
  return logout(request);
}

export async function loader({ request }: LoaderFunctionArgs) {
  return logout(request);
}
