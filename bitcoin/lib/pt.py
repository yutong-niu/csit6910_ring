class Point:
    """
    a Point on a specific Elliptic Curve
    """

    def __init__(self, x, y, a, b):
        self.a = a  # curve param
        self.b = b  # curve param
        self.x = x  # x-coord
        self.y = y  # y-coord
        if self.x is None and self.y is None:  # point at infinity
            return
        if self.y**2 != self.x**3 + a * x + b:  # check point on the curve
            raise ValueError('({}, {}) is not on the curve'.format(x, y))

    def __eq__(self, other):  # same curve and same coordinates
        return self.x == other.x and self.y == other.y \
            and self.a == other.a and self.b == other.b

    def __ne__(self, other):
        # the inverse of the == operator
        return not (self == other)

    def __repr__(self):
        if self.x is None:
            return 'Point(infinity)'
        else:
            return 'Point({},{})_{}_{}'.format(self.x, self.y, self.a, self.b)

    def __add__(self, other):  # overload + operator
        if self.a != other.a or self.b != other.b:
            raise TypeError('Points {}, {} are not on the same curve'.format
            (self, other))

        if self.x is None:  # self is point at infinity
            return other
        if other.x is None:  # other is point at infinity
            return self

        # Case 1: self.x == other.x, self.y != other.y
        # Result is point at infinity
        if self.x == other.x and self.y != other.y:
            return self.__class__(None, None, self.a, self.b)

        # Case 2: self.x ≠ other.x
        # Formula (x3,y3)==(x1,y1)+(x2,y2)
        # s=(y2-y1)/(x2-x1)
        # x3=s**2-x1-x2  (Vieta's formula)
        # y3=s*(x1-x3)-y1
        if self.x != other.x:
            s = (other.y - self.y) / (other.x - self.x)
            x = s**2 - self.x - other.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)

        # Case 3: self == other
        # Formula (x3,y3)=(x1,y1)+(x1,y1)
        # s=(3*x1**2+a)/(2*y1)
        # x3=s**2-2*x1
        # y3=s*(x1-x3)-y1
        if self == other and self.y == 0 * self.x:
            return self.__class__(None, None, self.a, self.b)
        if self == other:
            s = (3 * self.x**2 + self.a) / (2 * self.y)
            x = s**2 - 2 * self.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)

    def __rmul__(self, coefficient):
        coef = coefficient
        current = self  # 1 * self
        result = self.__class__(None, None, self.a, self.b)  # result starts at infinity
        while coef:
            if coef & 1:  # add the current value if right-most bit is 1
                result += current
            current += current  # double the current value
            coef >>= 1  # bit-shift to the right
        return result