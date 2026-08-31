// geo-distance.js
//
// Расстояние по прямой между двумя точками на сфере (формула гаверсинуса).
// Используется для сортировки прокси по близости к посетителю — НЕ для
// сравнения "город == город": у дата-центровых IP город из geoIP часто
// указывает на офис хостера, а не на физическое расположение сервера,
// поэтому единственный надёжный критерий здесь — расстояние в километрах
// между координатами, а не текстовое совпадение.

const EARTH_RADIUS_KM = 6371;

function toRad(deg) {
  return (deg * Math.PI) / 180;
}

// Расстояние в км между (lat1, lon1) и (lat2, lon2).
export function haversineDistanceKm(lat1, lon1, lat2, lon2) {
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return EARTH_RADIUS_KM * c;
}
