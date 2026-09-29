/* One asset, full page: where it is, the evidence, the quantum risk, the fix, what it depends on, and how the
   engine scored it (components/AssetPanel.jsx holds the sections). */
import { AssetPage } from '../components/AssetPanel';

export default function Asset({ route }) {
  return <AssetPage id={decodeURIComponent(route.segments[1] || '')} section={route.segments[2]} />;
}
